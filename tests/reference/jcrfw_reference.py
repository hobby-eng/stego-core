"""Independent dense paper-equation oracle on tiny synthetic images.

Uses explicit dense matrices/projections and a simultaneous KKT root solve,
not the Rust implementation's separable tiles or majorization iteration.
S-UNIWARD follows the reference convention (convolution, 16-pixel symmetric
extension, residuals in the margin included); its costs are checked against
golden values that conseal produced once. Dependencies are hash-pinned by
requirements-jmipod.txt. No steganography implementation or author source is
imported.
"""
import json
import math
import numpy as np
from scipy.optimize import least_squares
from scipy.signal import convolve2d, correlate2d

# conseal suniward.compute_cost_adjusted on the 40x36 image of golden_image(),
# (row, column, cost); the same values as the Rust golden test.
GOLDEN = [(0, 0, 0.9303344880837328), (0, 35, 0.6159422469064788),
          (39, 0, 1.3020905309834507), (39, 35, 1.5475590094414975),
          (1, 17, 0.9265457666805759), (5, 5, 0.5974107280647054),
          (12, 30, 0.7832051672361278), (20, 18, 0.7886629169177521),
          (27, 3, 0.614459566348893), (33, 22, 0.6487565867382524),
          (38, 11, 0.8055095156653691), (16, 34, 0.7597154495302962)]
GOLDEN_SUM = 1166.1652890418688


def dct_basis(n):
    return np.array([[math.sqrt((1 if k == 0 else 2) / n)
                      * math.cos(math.pi * k * (2*x+1) / (2*n))
                      for x in range(n)] for k in range(n)])


def mirror(i, n):
    i %= 2*n
    return i if i < n else 2*n-1-i


def wavelet_filters():
    polynomial = [math.comb(7+k, k) for k in range(8)]
    factors = []
    for y in np.polynomial.polynomial.polyroots(polynomial):
        factors.append(min(np.roots([1, 4*y-2, 1]), key=abs))
    coefficients = np.array([1.+0j])
    for _ in range(8):
        coefficients = np.convolve(coefficients, [1, 1])
    for root in factors:
        coefficients = np.convolve(coefficients, [1, -root])
    coefficients = coefficients.real * (math.sqrt(2) / coefficients.real.sum())
    return coefficients[::-1], coefficients * np.array([-1 if i % 2 == 0 else 1 for i in range(16)])


def spatial_costs(image):
    """S-UNIWARD costs, sigma = 1: the full convolution W = K * X over the symmetric
    16-pixel extension; a pixel's cost sums |K| over the residuals it enters,
    sum_t |K(t)| / (1 + |W(x + t)|), over the three bands; cropped to the image."""
    lo, hi = wavelet_filters()
    pad = 16
    extended = np.pad(image, pad, mode='symmetric')
    cost = np.zeros_like(extended)
    for vertical, horizontal in ((lo, hi), (hi, lo), (hi, hi)):
        kernel = np.outer(vertical, horizontal)
        response = convolve2d(extended, kernel, mode='full')
        cost += correlate2d(1/(1+abs(response)), abs(kernel), mode='valid')
    return cost[pad:-pad, pad:-pad]


def check_golden():
    y, x = np.mgrid[0:40, 0:36]
    cost = spatial_costs((2 + (7*y*y + 13*x*y + 29*x + 3*y) % 251).astype(float))
    worst = max(abs(cost[r, c]/value - 1) for r, c, value in GOLDEN)
    worst = max(worst, abs(cost.sum()/GOLDEN_SUM - 1))
    if worst > 1e-8:
        raise RuntimeError(f'S-UNIWARD convention misses the conseal golden values by {worst:e}')
    return worst


def parameters():
    wide, high = 3, 2
    coefficients = np.array([((i*17+i//64) % 31)-15 for i in range(384)], dtype=float).reshape(6, 8, 8)
    d = dct_basis(8)
    image = np.zeros((high*8, wide*8))
    for block in range(6):
        by, bx = divmod(block, wide)
        image[by*8:by*8+8, bx*8:bx*8+8] = d.T @ (coefficients[block]*2) @ d
    means = np.zeros_like(image)
    variances = np.zeros_like(image)
    for y, x in np.ndindex(image.shape):
        values = np.array([image[yy, xx] if yy < high*8 and xx < wide*8 else 0
                           for yy in (y, y+1) for xx in (x, x+1)])
        means[y, x] = values.mean()
        variances[y, x] = ((values-values.mean())**2).mean()
    global_noise = variances.mean()
    residual = (image-means) * np.minimum(1, np.divide(global_noise, variances,
                                                     out=np.zeros_like(image), where=variances > 0))
    five = dct_basis(5)
    h = np.array([np.outer(five[u], five[v]).ravel() for u in range(3) for v in range(3-u)]).T
    projector = np.eye(25)-h@h.T
    noise = np.zeros_like(image)
    spatial_variance = np.zeros_like(image)
    for y, x in np.ndindex(image.shape):
        window = np.array([residual[mirror(y+dy, high*8), mirror(x+dx, wide*8)]
                           for dy in range(-2, 3) for dx in range(-2, 3)])
        projected = projector @ (window-window[0])
        spatial_variance[y, x] = projected @ projected / 19
        noise[y, x] = projected[12]
    spatial_cost = spatial_costs(image)
    coefficient_variance = []
    weights = []
    noises = []
    for block in range(6):
        by, bx = divmod(block, wide)
        region = np.s_[by*8:by*8+8, bx*8:bx*8+8]
        coefficient_variance.append(np.maximum((d*d) @ spatial_variance[region] @ (d*d).T / 4, 1e-10).ravel())
        weights.append(spatial_cost[region].sum())
        n = noise[region].ravel()
        noises.append(n-n.mean())
    correlations = {}
    for i in range(6):
        for j in (i+1, i+3):
            if j >= 6 or (j == i+1 and i//3 != j//3):
                continue
            norm = np.linalg.norm(noises[i])*np.linalg.norm(noises[j])
            correlations[i, j] = float(np.clip(noises[i]@noises[j]/norm, -.99, .99)) if norm else 0
    return image, global_noise, coefficient_variance, weights, correlations


def solve(positions, payload, variances, weights, correlations):
    count = len(positions)
    matrix = np.zeros((count, count))
    index = {position: i for i, position in enumerate(positions)}
    for i, position in enumerate(positions):
        block, mode = divmod(position, 64)
        m = 5 if mode in (55, 62, 63) else 1
        variance = variances[block][mode]
        matrix[i, i] = m*weights[block]/variance**2
        for (a, b), r in correlations.items():
            if block not in (a, b):
                continue
            other = b if block == a else a
            w = (weights[a]+weights[b])/2 / (1-r*r)**2
            matrix[i, i] += m*w/variance**2
            j = index.get(other*64+mode)
            if j is not None:
                matrix[i, j] = m*w*r*r/(variance*variances[other][mode])
    scale = np.max(np.diag(matrix))
    matrix /= scale
    ln2 = math.log(2)

    def evaluate(values):
        rho, log_lambda = values[:-1], values[-1]
        e = np.exp(-rho)
        beta = e/(1+2*e)
        gradient = matrix@beta
        entropy = (-2*beta*np.log(beta)-(1-2*beta)*np.log1p(-2*beta)).sum()/ln2
        residual = np.r_[np.log(gradient)-log_lambda-np.log(rho/ln2), (entropy-payload)/payload]
        return residual, beta, entropy

    # Deliberately simultaneous nonlinear solve, independent of frozen-ratio MM.
    answer = least_squares(lambda x: evaluate(x)[0], np.r_[np.full(count, 3.), -3.],
                           bounds=(np.r_[np.full(count, 1e-12), -700.],
                                   np.r_[np.full(count, 700.), 700.]),
                           xtol=1e-14, ftol=1e-14, gtol=1e-14, max_nfev=1000)
    residual, beta, entropy = evaluate(answer.x)
    if not answer.success or np.max(abs(residual)) > 1e-9:
        raise RuntimeError(f'independent solve failed: {answer.message}; {residual}')
    return {'positions': positions, 'payload': payload, 'beta': beta.tolist(),
            'lambda': float(math.exp(answer.x[-1])*scale), 'entropy': float(entropy),
            'energy': float(beta@matrix@beta*scale), 'residual': float(np.max(abs(residual)))}


def main():
    golden = check_golden()
    _, global_noise, variances, weights, correlations = parameters()
    positions = [1, 65, 129, 257, 321, 55, 119, 5]
    result = {'golden_worst': golden, 'global_noise': float(global_noise), 'variances': [v[[0, 1, 5, 55]].tolist() for v in variances],
              'weights': [float(x) for x in weights],
              'correlations': {f'{a}-{b}': r for (a, b), r in correlations.items()},
              'solutions': [solve(positions, payload, variances, weights, correlations) for payload in (0.4, 2.4, 8.0)]}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
